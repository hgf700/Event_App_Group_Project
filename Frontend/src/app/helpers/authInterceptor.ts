
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);

  return next(
    req.clone({ withCredentials: true })
  ).pipe(
    catchError(error => {
      if (error.status === 401) {
        router.navigate(['/unauthorised'], {
          queryParams: { returnUrl: router.url }
        });
      } else if (error.status === 403) {
        router.navigate(['/forbidden']);
      } else if (error.status === 404) {
        router.navigate(['/not-found']);
      } else if (error.status >= 500) {
        router.navigate(['/server-error']);
      }

      return throwError(() => error);
    })
  );
};
