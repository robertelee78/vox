// A complete app read has one deadline, including a sequence of bounded daemon requests.
// Unstructured work is intentional: a cancelled FFI call must not hold the timeout's return.
import Foundation

@MainActor
enum AppRequest {
    static func run<Value>(_ words: String, seconds: UInt64 = 60,
                           _ operation: @escaping @MainActor () async throws -> Value) async throws -> Value {
        let pending = PendingAppRequest<Value>()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending.continuation = continuation
                pending.work = Task {
                    do { pending.finish(.success(try await operation())) }
                    catch { pending.finish(.failure(error)) }
                }
                pending.deadline = Task {
                    do { try await Task.sleep(nanoseconds: seconds * 1_000_000_000) }
                    catch { return }
                    pending.finish(.failure(AppRequestTimeout(words: words, seconds: seconds)))
                }
                if Task.isCancelled { pending.finish(.failure(CancellationError())) }
            }
        } onCancel: {
            Task { @MainActor in pending.finish(.failure(CancellationError())) }
        }
    }
}

@MainActor
private final class PendingAppRequest<Value> {
    var continuation: CheckedContinuation<Value, Error>?
    var work: Task<Void, Never>?
    var deadline: Task<Void, Never>?

    func finish(_ result: Result<Value, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        work?.cancel()
        deadline?.cancel()
        work = nil
        deadline = nil
        continuation.resume(with: result)
    }
}

private struct AppRequestTimeout: LocalizedError {
    let words: String
    let seconds: UInt64
    var errorDescription: String? { "\(words) did not finish within \(seconds) seconds. Whether it finished is unknown; check before trying again." }
}
