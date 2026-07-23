import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { RetryHelper } from '../helpers/ResilianceHelpers';
import { getEventDto } from '../Dto/getEventDto';

@Injectable({ providedIn: 'root' })
export class EventService {
  private apiUrl = 'https://localhost:7051/api/v1/Event';
  event: getEventDto[] = [];

  constructor(private http: HttpClient) {}

  getEvents(page: number, pageSize: number): Observable<getEventDto[]> {
    const params = new HttpParams()
      .set('page', page)
      .set('pageSize', pageSize);
    
    return this.http.get<getEventDto[]>(`${this.apiUrl}/get-events`, {
       headers: getAuthHeaders(), 
       params,
      });
  }

  eventDetails(eventId: number) {
    return this.http.get<getEventDto>(`${this.apiUrl}/event-details/${eventId}`, {
      headers: getAuthHeaders(),
    });
  }


}
