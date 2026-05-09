import { HttpClient } from '@angular/common/http';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getEventDto } from '../Dto/getEventDto';

@Injectable({ providedIn: 'root' })
export class EventService {
  private apiUrl = 'https://localhost:7051/api/v1/Event';
  event: getEventDto[] = [];

  constructor(private http: HttpClient) {}

  getEvents() {
    return this.http.get<getEventDto[]>(`${this.apiUrl}/get-events`, { headers: getAuthHeaders() });
  }

  eventDetails(eventId: number) {
    return this.http.get<getEventDto>(`${this.apiUrl}/event-details/${eventId}`, {
      headers: getAuthHeaders(),
    });
  }

  seedDataBase() {
    return this.http.post(`${this.apiUrl}/seed-database`, {}, { headers: getAuthHeaders() });
  }
}
