import { HttpClient } from '@angular/common/http';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getEventDto } from '../Dto/getEventDto';

@Injectable({ providedIn: 'root' })
export class DownloadImportEventService {
  private apiUrl = 'https://localhost:7051/api/v1/Event';
  private apiUrlSearch = 'https://localhost:7051/api/v1/SearchAndImportEvents';

  event: getEventDto[] = [];

  constructor(private http: HttpClient) {}

  // searchAndImportEvents(city: string){
  //     return this.http.post(
  //       `${this.apiUrl}/seed-database/${city}`,
  //       {},
  //       { headers: getAuthHeaders() }
  //     );
  //   }

  //   getSearchAndImportEvents(){
  //     return this.http.get<getEventDto[]>(
  //       `${this.apiUrl}/get-events`,
  //       { headers: getAuthHeaders() }
  //     );
  //   }

  searchEvent(city: string) {
    let params = new HttpParams().set('city', city);

    return this.http.get<getEventDto[]>(`${this.apiUrlSearch}/search-event`, {
      headers: getAuthHeaders(),
      params,
    });
  }
}
