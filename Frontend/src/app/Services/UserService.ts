import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getCurrentUserDto } from '../Dto/getCurrentUserDto';
import { postEditUserDto } from '../Dto/postEditUserDto';
import { getEventDto } from '../Dto/getEventDto';

@Injectable({ providedIn: 'root' })
export class UserService {
  private apiUrl = 'https://localhost:7051/api/v1/User';
  editUser!: postEditUserDto;
  currentUser!: getCurrentUserDto;
  event: getEventDto[] = [];

  constructor(private http: HttpClient) {}

  getCurrentUser() {
    return this.http.get<getCurrentUserDto>(
      `${this.apiUrl}/current-user}`,
      { headers: getAuthHeaders() },
    );
  }

  currentUserTickets() {
    return this.http.get<getEventDto[]>(
      `${this.apiUrl}/user-tickets}`,
      { headers: getAuthHeaders() },
    );
  }

  editCurrentUser() {
    return this.http.post<postEditUserDto>(
      `${this.apiUrl}/edit-user}`,
      {},
      { headers: getAuthHeaders() },
    );
  }

}