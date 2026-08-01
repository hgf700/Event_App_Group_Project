import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getUserBoughtTicketDto } from '../Dto/getUserBoughtTicketDto';

@Injectable({ providedIn: 'root' })
export class UserTicketService {
  private apiUrl = 'https://localhost:7051/api/v1/UserTicket';

  constructor(private http: HttpClient) {}

  currentUserTickets() {
    return this.http.get<getUserBoughtTicketDto[]>(
      `${this.apiUrl}/user-tickets`,
      { headers: getAuthHeaders() },
    );
  }


}