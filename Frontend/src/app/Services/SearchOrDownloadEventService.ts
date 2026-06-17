import { HttpClient } from '@angular/common/http';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getEventDto } from '../Dto/getEventDto';

@Injectable({ providedIn: 'root' })
export class SearchOrDownloadEventService {
  private apiUrl = 'https://localhost:7051/api/v1/SearchOrDownload';

  event: getEventDto[] = [];

  constructor(private http: HttpClient) {}

  searchOrDownloadEvent(city: string) {
    let params = new HttpParams().set('city', city);

    return this.http.post<getEventDto[]>(`${this.apiUrl}/search-event-or-download`, 
      {},
      {
      headers: getAuthHeaders(),
      params,
    });
  }

  seedDataBase() {
    return this.http.post(`${this.apiUrl}/seed-database`, 
      {},
      { headers: getAuthHeaders() }
    );
  }
}
