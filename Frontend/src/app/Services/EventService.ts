import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { RetryHelper } from '../helpers/ResilianceHelpers';
import { getEventDto } from '../Dto/getEventDto';
import { paginatedResponse } from '../model/paginatedResponse';
import { getEventTicketWithQrDto } from '../Dto/getEventQrCodeInfoDto';

@Injectable({ providedIn: 'root' })
export class EventService {
  private apiUrl = 'https://localhost:7051/api/v1/Event';
  private apiUserTicketUrl = 'https://localhost:7051/api/v1/UserTicket';

  constructor(private http: HttpClient) {}

  getEvents(page: number, pageSize: number): Observable<paginatedResponse<getEventDto>> {
    
    return this.http.get<paginatedResponse<getEventDto>>
      (`${this.apiUrl}/get-events?page=${page}&pageSize=${pageSize}`, {
       headers: getAuthHeaders(),
      });
  }

  eventDetails(eventId: number) {
    return this.http.get<getEventDto>(`${this.apiUrl}/event-details/${eventId}`, {
      headers: getAuthHeaders(),
    });
  }

  getTicketsWithQr(eventId: number): Observable<getEventTicketWithQrDto> {
    return this.http.get<getEventTicketWithQrDto>(
      `${this.apiUserTicketUrl}/ticket-detail-with-qr/${eventId}`,
      { headers: getAuthHeaders() },
    );
  }

}
