import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';

@Injectable({ providedIn: 'root' })
export class AdminService {
  private apiUrl = 'https://localhost:7051/api/v1/Admin';

  constructor(private http: HttpClient) {}

  seedDataBase() {
    return this.http.post(`${this.apiUrl}/admin-seed-database`, {});
  }
}