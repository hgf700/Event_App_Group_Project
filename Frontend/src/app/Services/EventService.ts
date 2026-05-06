import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';

@Injectable({ providedIn: 'root' })
export class SeedService {
  private apiUrl = 'https://localhost:7051/api/v1/Event';

  constructor(
    private http: HttpClient
  ) {}

  seedDataBase() {
    return this.http.post(
      `${this.apiUrl}/seed-database`,
      {},
      { headers: getAuthHeaders() }
    );
  }
}