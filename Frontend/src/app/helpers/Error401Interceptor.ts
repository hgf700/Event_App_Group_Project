// import { inject } from '@angular/core';
// import { HttpInterceptorFn } from '@angular/common/http';
// import { catchError, switchMap, throwError } from 'rxjs';
// import { Router } from '@angular/router';
// import { AuthService } from '../Services/AuthService';
// import { LayoutService } from '../Services/LayoutService';

// export const Error401Interceptor: HttpInterceptorFn = (req, next) => {

//   const authService = inject(AuthService);
//   const layoutService = inject(LayoutService);
//   const router = inject(Router);

//   return next(req).pipe(
//     catchError((error) => {

//       if (error.status === 401 && !req.url.includes('/auth/refresh')) {

//         return authService.refreshToken().pipe(

//           switchMap((response) => {

//             localStorage.setItem('jwt', response.jwt);

//             const retryReq = req.clone({
//               setHeaders: {
//                 Authorization: `Bearer ${response.jwt}`
//               }
//             });

//             return next(retryReq);
//           }),

//           catchError((refreshError) => {

//             layoutService.logout();
//             router.navigate(['/login']);

//             return throwError(() => refreshError);
//           })
//         );
//       }

//       return throwError(() => error);
//     })
//   );
// };