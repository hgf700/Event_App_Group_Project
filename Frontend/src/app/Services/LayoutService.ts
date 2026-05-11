import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class LayoutService {

  private apiUrl = 'https://localhost:7051/api/v1/auth';

  constructor(private http: HttpClient) {}

  isAuthenticated(): boolean {
    return !!localStorage.getItem('token');
  }

  userEmail(): string {
    return localStorage.getItem('email') || '';
  }

  logout(): void {

    localStorage.removeItem('token');
    localStorage.removeItem('email');

    window.location.href = '/login';
  }
}