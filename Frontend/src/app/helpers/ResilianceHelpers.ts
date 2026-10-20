import {
  Observable,
  throwError,
  timer,
  TimeoutError,
} from 'rxjs';
import {
  retry,
  timeout,
  catchError,
  tap,
} from 'rxjs/operators';

export interface ResilienceOptions {
  /** Timeout pojedynczego requestu (ms) */
  timeoutMs?: number;
  /** Maksymalna liczba ponowień (nie licząc pierwszego requestu) */
  maxRetries?: number;
  /** Bazowy delay między retry (ms) – będzie rosnął */
  baseDelayMs?: number;
  /** Maksymalny delay między retry (ms) */
  maxDelayMs?: number;
  /** Czy logować błędy */
  logErrors?: boolean;
}

const DEFAULT_OPTIONS: Required<ResilienceOptions> = {
  timeoutMs: 3000,
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 10000,
  logErrors: true,
};

/**
 * Resilience pipe z:
 * - timeoutem
 * - retry z exponential backoff + jitter
 * - sensownym catchError
 */
export function resiliencePipe<T>(options: ResilienceOptions = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  return (source: Observable<T>) =>
    source.pipe(
      timeout(opts.timeoutMs),

      retry({
        count: opts.maxRetries,
        delay: (error, retryCount) => {
          // Exponential backoff + jitter
          const exponentialDelay = Math.min(
            opts.baseDelayMs * Math.pow(2, retryCount - 1),
            opts.maxDelayMs,
          );
          const jitter = Math.random() * 300; // 0–300ms
          const delay = exponentialDelay + jitter;

          if (opts.logErrors) {
            console.warn(
              `[Resilience] Retry ${retryCount}/${opts.maxRetries} za ${Math.round(delay)}ms`,
              error,
            );
          }

          return timer(delay);
        },
        // Retryujemy tylko wybrane błędy (opcjonalnie)
        // resetOnSuccess: true, // domyślnie true
      }),

      catchError((err) => {
        if (opts.logErrors) {
          if (err instanceof TimeoutError) {
            console.error('[Resilience] Request timed out');
          } else {
            console.error('[Resilience] Request failed after retries:', err);
          }
        }
        return throwError(() => err);
      }),
    );
}