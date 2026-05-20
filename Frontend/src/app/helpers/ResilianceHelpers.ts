import { retry, timeout ,catchError, throwError, Observable, timer } from 'rxjs';

export function RetryHelper<T>() {
  return (source: any) => source.pipe(retry(3));
}

export function TimeoutHelper<T>() {
  return (source: any) => source.pipe(timeout(5000));
}

export function TotalTimeoutHelper<T>() {
  return (source: any) => source.pipe(timeout(10000));
}

export function resiliencePipe<T>() {
  return (source: any) =>
    source.pipe(
      // timeout(5000),

      retry({
        count: 3,
        delay: (error, retryCount) => timer(retryCount * 1000)
      }),

      catchError(err => {
        console.error('Request failed:', err);
        return throwError(() => err);
      })
    );
}

class CircuitBreaker {
  private failures = 0;
  private lastFailTime = 0;
  private state: 'CLOSED' | 'OPEN' = 'CLOSED';

  constructor(
    private threshold = 5,
    private cooldown = 10000
  ) {}

  execute<T>(source: Observable<T>) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailTime > this.cooldown) {
        this.state = 'CLOSED';
        this.failures = 0;
      } else {
        return throwError(() => new Error('Circuit breaker OPEN'));
      }
    }

    return new Observable<T>(observer => {
      source.subscribe({
        next: v => {
          this.failures = 0;
          observer.next(v);
        },
        error: err => {
          this.failures++;
          this.lastFailTime = Date.now();

          if (this.failures >= this.threshold) {
            this.state = 'OPEN';
          }

          observer.error(err);
        },
        complete: () => observer.complete()
      });
    });
  }
}

