// import { HttpClient } from '@angular/common/http';
// import { Injectable } from '@angular/core';
// import { getAuthHeaders } from '../helpers/GetAuthHeaders';

// @Injectable({ providedIn: 'root' })
// export class RefreshTokenRequestService implements HttpInterceptor {

//   constructor(private authService: AuthService) {}

//   intercept(req: HttpRequest<any>, next: HttpHandler) {

//     return next.handle(req).pipe(

//       catchError(error => {

//         if (error.status === 401) {

//           return this.authService.refreshToken()
//             .pipe(
//               switchMap(response => {

//                 const newRequest = req.clone({
//                   setHeaders: {
//                     Authorization: `Bearer ${response.accessToken}`
//                   }
//                 });

//                 return next.handle(newRequest);
//               })
//             );
//         }

//         return throwError(() => error);
//       })
//     );
//   }
// }