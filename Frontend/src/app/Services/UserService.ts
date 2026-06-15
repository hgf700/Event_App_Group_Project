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

  getCurrentUserEmail() {
    return this.http.get<getCurrentUserDto>(
      `${this.apiUrl}/current-user`,
      { headers: getAuthHeaders() },
    );
  }

  currentUserTickets() {
    return this.http.get<getEventDto[]>(
      `${this.apiUrl}/user-tickets`,
      { headers: getAuthHeaders() },
    );
  }

  editCurrentUserEmail(newEmail: string) {
    return this.http.post(
      `${this.apiUrl}/edit-user`,
      newEmail,
      { headers: getAuthHeaders() },
    );
  }

  editCurrentUserPassword(newPassword: string) {
    return this.http.post(
      `${this.apiUrl}/edit-user`,
      newPassword,
      { headers: getAuthHeaders() },
    );
  }

}