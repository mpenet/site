Title: So you wrote a Ring adapter
Date: 2026-10-12
Tags: clojure, enso, jvm, http, servers

A Ring adapter is the easiest thing you will ever write. It is also one of the
hardest, and the gap between those two sentences is the whole story. I spent the
last while closing that gap — the thing that came out of it is called
[enso](https://github.com/mpenet/enso), a zero-dependency HTTP/1.1, HTTP/2,
HTTP/3 and WebSocket server for Ring — so let me walk you from the easy version
to the one you can actually point at the internet, one missed corner at a time.

Here is the easy version. You have seen it, you have probably written it.

```clojure
(defn serve [handler port]
  (let [server (ServerSocket. port)]
    (future
      (loop []
        (let [sock (.accept server)]
          (future
            (with-open [s sock]
              (let [req  (parse-request (.getInputStream s))
                    resp (handler req)]
                (write-response (.getOutputStream s) resp)))))
        (recur)))
    server))
```

Accept a socket, parse a request, call the handler, write the response.  A
thread per connection. On JDK 21 you make those virtual threads and it even
scales. `curl localhost:8080` returns your `{:status 200 :body "hello"}`. The
README example passes. Ship it.

Unsurprisingly, it is completely broken. Not in a "needs polish" way — in a "do
not put this on a network" way please. Let me show you.

## Where does the body end?

`parse-request` read the headers. Did it read the body? A `GET` has none, so
your tests pass. A `POST` with `Content-Length: 1048576` has a megabyte the
handler may or may not read. If your handler ignores `:body` — plenty do — those
bytes are still sitting in the socket when you go to write the response and read
the next request. Now you are parsing a request body as if it were a request
line. On a keep-alive connection you have desynchronised yourself from the
client, and every response after is garbage.

So you need a real framing layer: Content-Length *and* chunked
transfer-encoding, the knowledge that `HEAD` and `204` and `304` carry no body
regardless of their headers, and a rule for what happens to a body the handler
never read (you drain it, within a bound — more on bounds later). None of this
is in the forty lines. All of it is mandatory.

## The client that says nothing

Open a socket to the easy version. Send nothing. `parse-request` blocks on a
read that never returns. That is one virtual thread gone. Cheap, sure. Now open
ten thousand of them, each dribbling one byte every twenty-nine seconds — slow
enough that no single read times out, because *there is no timeout*. This is
slowloris, it is from 2009, and your forty lines have no answer to it.

A real adapter has a small forest of clocks, and they are all different:

- a **handshake** deadline (TLS can stall too),
- a **header** deadline — the whole request head, wall-clock, from its
  first byte, because a per-read timeout resets every time one byte
  arrives,
- a **read** timeout between body chunks,
- an **idle** timeout between requests on a kept-alive connection,
- and a **minimum data rate** — Kestrel uses 240 bytes/second after a 5
  second grace, and so, it turns out, do I — because a client sending one
  byte every twenty-nine seconds technically keeps making progress
  forever.

The easy version has none of these. Each one is a real decision with a
real default, and getting the defaults wrong is its own bug.

## The two parsers that disagree

Send this:

```
POST / HTTP/1.1
Host: x
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
...
```

Your naive parser picks one of `Content-Length` or `Transfer-Encoding` and moves
on. The proxy in front of you picks the other. Now the two of you disagree about
where the first request ends and the second begins, and I have smuggled a second
request past whatever the proxy thought it was authorising. This is request
smuggling, and it is not a parsing nit — it is a security boundary that exists
*between* your parser and someone else's.

So: reject a message with both framing headers. Reject duplicate
`Content-Length`. Reject a bare `LF` line ending where the spec wants
`CRLF`. Reject obs-fold — the obsolete trick of continuing a header value onto
the next line by starting it with a space, which two parsers routinely
disagree about. Reject a chunk size that overflows a long. Validate the request
target and the `Host` authority. Every one of these is a line in an RFC and a
CVE in someone's tracker, and "I'll be lenient, it's friendlier" is exactly how
you end up on the wrong side of one.

## Closing is harder than opening

Your handler returns a `400`. You write it and close the socket. Clean,
right?

Except the client was still uploading its body when you decided to reject
it. There are unread bytes in the kernel's receive buffer. On most operating
systems, closing a socket with unread input sends a TCP `RST` — the abrupt
"forget this connection ever existed" reset — and a reset blows away the send
buffer too, *including the 400 you just wrote*. The client never sees your
error. It sees a connection reset and has no idea why.

The fix is counterintuitive: to close correctly you close *slower*. You shut
down the write side, then keep reading and discarding input until the peer
closes or a short deadline passes, so your response drains out before the
socket goes away. There's a TLS twist too. An HTTP/1.0 response with no
`Content-Length` is delimited by the connection closing, so the receiver can't
otherwise tell "body ended here" from "body got cut off." TLS normally ends
with a `close_notify` alert meaning "this was a clean, complete shutdown" — so
when you're *abandoning* a body mid-stream, you deliberately close *without*
that alert, which is exactly the signal that lets the client tell a truncated
body from a finished one. These are the kind of corners you only find by
watching a real client get a reset where you sent a response.

## Then you add HTTP/2 and the threat model changes

One TCP connection is now many streams. Most of the above still applies, per
stream, but there is a new category: the connection is a shared resource a
single client can turn against you.

The famous one is rapid reset —
[CVE-2023-44487](https://www.cve.org/CVERecord?id=CVE-2023-44487), the one that
took out a chunk of the internet in 2023. A client opens a stream, you start
doing work, the client immediately sends `RST_STREAM`.  Repeat as fast as the
wire allows. Each reset is cheap for the client and not cheap for you. There is
a sequel, MadeYouReset, where the client doesn't send `RST_STREAM` at all —
it sends a frame that's malformed in just the right way (a stray
`WINDOW_UPDATE`, say) so that *you*, the server, are forced to reset the stream
in response. The work still happened, but the reset came from your side, so your
own rapid-reset counter never trips — unless you count the resets you initiate
on the client's behalf too, which is the sort of thing you only think of after
reading the first CVE very carefully.

So you add reset accounting, a cap on CONTINUATION floods (an unending run of
header-continuation frames that stretches one request's headers forever), empty-
DATA flood detection (zero-length `DATA` frames that cost the attacker nothing
and you a syscall each), flow-control-window bookkeeping that survives a stream
being reset mid-frame, yadda-yadda... The handler still just returns a map. All
of this lives underneath.

## And now the hard one

Here is the question I underestimated the longest, and it is so easy to
state that it hides how hard it is:

> When a client sends data faster than your handler reads it, where does
the data go?

The forty-line version has an answer by accident: into an unbounded
buffer, until you run out of memory. One connection, one `OutOfMemory`,
whole server down. So you add a cap — a maximum number of buffered bytes
— and feel good.

Now the cap fills up. A client is uploading a 2 GB body to a handler that
reads slowly, or doesn't read at all, and you have hit your buffer limit.
What do you do?

The obvious thing — and I mean obvious, I did it, most servers I looked at do
some version of it — is to stop reading from that socket and let the clocks from
earlier run. Eventually the minimum-data-rate or read timeout fires and you
return a `408 Request Timeout`. Problem solved.

Except you just lied to the client. *You* stopped reading, to protect *your*
memory. The client was sending at a perfectly good rate the whole time; it is
blocked because your receive window is closed, which it is closed because you
chose not to drain it. Then you timed the client out for a stall you created and
blamed it in the logs. I know this happens because I ran a multi-hour soak with
a deliberately tiny memory budget and watched a pile of `408`s go to clients
that had done nothing wrong.

The honest version is more work, and some accounting, and it is the part of
[enso](https://github.com/mpenet/enso) I spent the most time getting right.

- **One budget for the whole server.** Not a per-connection buffer — a
  single pool of "bytes we are willing to hold on behalf of peers,"
  shared across HTTP/1.1, HTTP/2, HTTP/3 and WebSocket, enforced by
  back-pressure.
- **Fair shares.** Under pressure, one connection cannot hold more than
  its slice (the budget divided by the connections actually holding
  bytes), so one fat uploader can't freeze everyone else's uploads.
- **A floor, so the budget limits growth, never progress.** Every
  connection may always hold a small amount — the same 64 KB that HTTP/2
  hands every stream as its default window before anyone configures
  anything — so an upload on a connection under its floor keeps moving
  even when the global budget is exhausted. You throttle; you never fully
  stall.
- **Clocks that only count time the client could have used.** This is the
  fix for the lie. While the server is the one withholding reads — a
  receive window it has deliberately closed, a stream it has chosen not
  to drain — the read timeout and the data-rate clock for that body are
  *paused*. They resume when the server starts reading again. A client is
  only ever timed out for a stall it actually caused.

That last rule sounds small and it took real work to get right across three
protocols, because "the server is withholding" means something different in
each: HTTP/2 it's a connection window we haven't replenished, HTTP/3 it's a
stream the event loop isn't reading, WebSocket it's a message we've stopped
pulling because the budget is full. Same principle, three mechanisms.

And the payoff is a property you can state in one sentence: **the server never
blames a client for back-pressure the server applied.** Concretely: a client
only ever gets a `408 Request Timeout` when *it* actually went quiet — stopped
sending, stalled below the data-rate floor, genuinely slow. A client that was
sending as fast as the wire allowed, and only went idle because the server
clamped its flow-control window to protect its own memory, never collects the
blame for that pause. The timeout measures the client's behaviour, never the
server's self-defence. That distinction doesn't exist in the forty-line version
— it can't, because the forty-line version has no idea whether a silent socket
is a slow client or a window it closed itself.

I don't know how many other servers bother drawing that line, and I'd be glad to
be pointed at the ones that do — but it's the corner of
[Enso](https://github.com/mpenet/enso) I find myself caring about most.

## Doesn't all this blocking cost a thread?

Everything above is written in the blocking style the forty-line version
started with: read, block, parse, call the handler, write, repeat. And the
whole point of back-pressure is that it *stops reading* — a slow upload, or one
the budget is throttling, is a connection sitting on a blocked read for a long
time. On the classic thread-per-connection model that is exactly the disaster
slowloris exploited: ten thousand slow connections, ten thousand parked OS
threads, server dead.

The reason it isn't a disaster here is that the threads aren't OS threads. Each
HTTP/1.1 connection, and each HTTP/2 stream, runs on its own *virtual* thread. A
blocking read on a virtual thread unmounts it from its carrier — the parked
upload becomes a continuation on the heap, a few hundred bytes, not an idle
kernel thread. So a connection we've deliberately stopped reading from costs us
almost nothing to keep around, which is the whole trick: back-pressure that
blocks is the single cheapest thing you can do to a virtual thread, and
slowloris's ten thousand dribblers are ten thousand cheap heap objects, not ten
thousand threads.

The clocks don't cost a thread each either. Every handshake, header, idle and
data-rate deadline across every connection and protocol lives in one hashed
timing wheel on a single daemon thread; arming a timeout is appending to a
bucket, not spawning anything.

HTTP/3 is the one that works the other way, and it's worth saying because it's
the exception. Its I/O runs on a small fixed pool of event-loop threads — by
default one per core — with every connection multiplexed across them and the
kernel steering datagrams by connection id. There, "withholding" a stream isn't
a blocked thread at all; it's the loop choosing not to drain that stream this
tick and moving on to the next. Different shape, same result: the cost of
holding a throttled peer is bounded and tiny, whether that peer is parked on a
virtual thread or skipped by an event loop.

## The moral, such as it is

The forty-line adapter isn't wrong because it's short. It's wrong because "serve
a request" is a surface over a long tail of concerns — framing, timeouts,
smuggling, resets, lingering close, back-pressure — that don't show up in the
demo and all show up in production. "Simple", was never "few lines." It's each of
those concerns handled once, cleanly, so that the person using it writes

```clojure
(enso/run-server (fn [req] {:status 200 :body "hello"}) {:port 8080})
```

and none of it leaks out.

And that's the pitch. Not that it's fast, [though it
is](https://github.com/mpenet/enso/blob/main/doc/performance.md).

And I have no illusion the list above is complete. Somewhere out there is a
client, or a proxy, or a single malformed frame that I haven't thought of yet,
and the day someone files the three-line repro for it is the day I learn about
corner number N+1. Find it? Open an issue. I collect them.
