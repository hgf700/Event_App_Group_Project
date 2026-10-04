import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';

@Injectable({ providedIn: 'root' })
export class AdminService {
  private apiSearchOrDownloadUrl = 'https://localhost:7051/api/v1/SearchOrDownload';

  constructor(private http: HttpClient) {}

  seedDataBase() {
    return this.http.post(`${this.apiSearchOrDownloadUrl}/seed-database`, {});
  }
}