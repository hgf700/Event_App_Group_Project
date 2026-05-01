import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class DevelopingLoginService {
  private apiUrl = 'https://localhost:7051/api/auth';

  constructor(private http: HttpClient) {}

  developingLogin(email: string) {
    return this.http.post<{ token: string }>(`${this.apiUrl}/dev-login`, {
      email,
    });
  }
}