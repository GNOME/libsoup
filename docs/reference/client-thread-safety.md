Title: Client thread safety
Slug: client-thread-safety

# Client thread safety

libsoup is not fully thread safe, but since version 3.2 it's possible
to send messages from any thread. The recommended and most efficient
way to use libsoup is using only the async API from a single thread,
even when it feels natural to use the sync API from a worker
thread. While there's not much difference in HTTP/1, in the case of
HTTP/2, two messages for the same host sent from different threads
will not use the same connection, so the advantage of HTTP/2
multiplexing is lost.

There are a few important things to consider when using multiple
threads:

 - Only the API to send messages can be called concurrently from
   multiple threads. So, in case of using multiple threads, you must
   configure the session (setting network properties, features, etc.)
   from the thread it was created and before any request is made.

 - All signals associated to a message
   ([signal@Session::request-queued],
   [signal@Session::request-unqueued], and all Message signals) are
   emitted from the thread that started the request, and all the IO will
   happen there too.

 - The session can be created in any thread, but all session APIs
   except the methods to send messages must be called from the thread
   where the session was created.

 - To use the async API from a thread different than the one where the
   session was created, the thread must have a thread default main
   context where the async callbacks are dispatched.

 - The sync API doesn't need any main context at all.


