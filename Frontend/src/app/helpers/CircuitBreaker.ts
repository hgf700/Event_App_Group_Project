import { Observable, throwError } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';

export class CircuitBreaker {
  private failures = 0;
  private lastFailTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';

  constructor(
    private readonly threshold = 5,
    private readonly cooldownMs = 15000,
  ) {}

  execute<T>(source: Observable<T>): Observable<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailTime > this.cooldownMs) {
        this.state = 'HALF_OPEN';
      } else {
        return throwError(() => new Error('Circuit breaker is OPEN'));
      }
    }

    return source.pipe(
      tap({
        next: () => this.onSuccess(),
        error: () => this.onFailure(),
      }),
      catchError((err) => {
        this.onFailure();
        return throwError(() => err);
      }),
    );
  }

  private onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  private onFailure() {
    this.failures++;
    this.lastFailTime = Date.now();

    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
      console.warn('[CircuitBreaker] OPEN – zbyt wiele błędów');
    }
  }
}