import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../Services/AuthService';

export const RefreshToken401Interceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const isRefreshRequest = req.url.includes('/api/v1/auth/refresh');

  const isLoginRequest =
    req.url.includes('/api/v1/auth/login-norm') ||
    req.url.includes('/api/v1/auth/sign-in-google') ||
    req.url.includes('/api/v1/auth/google-response');

  return next(req).pipe(
    catchError((error) => {
      if (error.status !== 401 || isRefreshRequest || isLoginRequest) {
        return throwError(() => error);
      }

      return authService.refreshToken().pipe(
        switchMap((response) => {
          const retryReq = req.clone({
            withCredentials: true,
            setHeaders: {
              Authorization: `Bearer ${response.accessToken}`,
            },
          });

          return next(retryReq);
        }),
        catchError((refreshError) => {
          authService.logout();
          router.navigate(['/login']);

          return throwError(() => refreshError);
        }),
      );
    }),
  );
};
