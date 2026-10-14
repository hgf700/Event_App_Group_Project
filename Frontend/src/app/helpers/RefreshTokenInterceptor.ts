import { inject } from '@angular/core';
import { HttpInterceptorFn } from '@angular/common/http';
import { catchError, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { AuthService } from '../Services/AuthService';

export const Error401Interceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const isRefreshRequest = req.url.includes('/api/v1/auth/refresh');
  const isLoginRequest = req.url.includes('/api/v1/auth/login-norm') ||
    req.url.includes('/api/v1/auth/sign-in-google') ||
    req.url.includes('/api/v1/auth/google-response');

  return next(req).pipe(
    catchError((error) => {
      if (
        error.status === 401 &&
        !isRefreshRequest &&
        !isLoginRequest
      ) {
        return authService.refreshToken().pipe(
          switchMap((response) => {
            const retryReq = req.clone({
              setHeaders: {
                Authorization: `Bearer ${response.accessToken}`
              }
            });

            return next(retryReq);
          }),
          catchError((refreshError) => {
            authService.logout();
            router.navigate(['/login']);

            return throwError(() => refreshError);
          })
        );
      }

      return throwError(() => error);
    })
  );
};
