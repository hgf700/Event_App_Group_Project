// import { inject } from '@angular/core';
// import { HttpInterceptorFn } from '@angular/common/http';
// import { catchError, switchMap, throwError } from 'rxjs';
// import { Router } from '@angular/router';
// import { AuthService } from '../Services/AuthService';

// export const Error401Interceptor: HttpInterceptorFn = (req, next) => {
//   const authService = inject(AuthService);
//   const router = inject(Router);

//   const isRefreshRequest = req.url.includes('/api/v1/refresh-token');
//   const isLoginRequest = req.url.includes('/login');

//   return next(req).pipe(
//     catchError((error) => {
//       if (
//         error.status === 401 &&
//         !isRefreshRequest &&
//         !isLoginRequest
//       ) {
//         return authService.refreshToken().pipe(
//           switchMap((response) => {
//             localStorage.setItem('jwt', response.accessToken);

//             const retryReq = req.clone({
//               setHeaders: {
//                 Authorization: `Bearer ${response.accessToken}`
//               }
//             });

//             return next(retryReq);
//           }),
//           catchError((refreshError) => {
//             authService.logout();
//             router.navigate(['/login']);

//             return throwError(() => refreshError);
//           })
//         );
//       }

//       return throwError(() => error);
//     })
//   );
// };
