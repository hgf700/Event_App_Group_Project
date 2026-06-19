import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import { getCurrentUserDto } from '../Dto/getCurrentUserDto';
import { postEditUserDto } from '../Dto/postEditUserDto';
import { getEventDto } from '../Dto/getEventDto';
import { postEditUserPassword } from '../Dto/postEditUserPassword';

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
      `${this.apiUrl}/edit-user-email`,
      {newEmail},
      { headers: getAuthHeaders() },
    );
  }

  editCurrentUserPassword(oldPassword: string, newPassword: string) {
    return this.http.post<postEditUserPassword>(
      `${this.apiUrl}/edit-user-password`,
      { oldPassword, newPassword },
      { headers: getAuthHeaders() },
    );
  }

}