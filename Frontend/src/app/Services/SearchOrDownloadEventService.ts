import { HttpClient } from '@angular/common/http';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getEventDto } from '../Dto/getEventDto';
import { postSearchEventDto } from '../Dto/postSearchEventDto';

@Injectable({ providedIn: 'root' })
export class SearchOrDownloadEventService {
  private apiUrl = 'https://localhost:7051/api/v1/SearchOrDownload';

  constructor(private http: HttpClient) {}

  searchOrDownloadEventForm(city: string) {
    const dto: postSearchEventDto = {
      city: city
    };

    return this.http.post<getEventDto[]>(
      `${this.apiUrl}/search-event-and-download`,
      dto,
      {
        headers: getAuthHeaders()
      }
    );
  }

  searchOrDownloadEventQuery(city: string) {
    const params = new HttpParams()
      .set('city', city);

    return this.http.post<getEventDto[]>(
      `${this.apiUrl}/search-event-and-download`,
      null,
      {
        headers: getAuthHeaders(),
        params
      }
    );
  }

  seedDataBase() {
    return this.http.post(`${this.apiUrl}/seed-database`, 
      {},
      { headers: getAuthHeaders() }
    );
  }
}
