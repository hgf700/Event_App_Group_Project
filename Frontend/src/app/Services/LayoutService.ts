import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { signal } from '@angular/core';

@Injectable({ providedIn: 'root', })
export class LayoutService {
  userEmailData = signal(
    localStorage.getItem('email') ?? ''
  );

  constructor(private http: HttpClient) {}

  setUserEmail(email: string) {
    this.userEmailData.set(email);
    localStorage.setItem('email', email);
  }

  isAuthenticated(): boolean {
    return !!localStorage.getItem('jwt');
  }

  // isAdmin(): boolean{
  //   const token = this.getToken();
  //   if (!token) return false;

  //   const payload = jwtDecode<any>(token);

  //   return payload.role === 'Admin';
  // }

  userEmail(): string {
    return this.userEmailData();
  }

  logout(): void {
    localStorage.removeItem('jwt');
    localStorage.removeItem('email');

    window.location.href = '/';
  }
}