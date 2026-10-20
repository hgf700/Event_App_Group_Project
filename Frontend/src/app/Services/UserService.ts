import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { postEditUserDto } from '../Dto/postEditUserDto';
import { getEventDto } from '../Dto/getEventDto';
import { postEditUserPassword } from '../Dto/postEditUserPassword';
import { getUserBoughtTicketDto } from '../Dto/getUserBoughtTicketDto';
import { environment } from '../../environments/environment';
import { resiliencePipe } from '../helpers/ResilianceHelpers';

@Injectable({ providedIn: 'root' })
export class UserService {
  private apiUrl = `${environment.apiUrl}/api/v1/user`;

  constructor(private http: HttpClient) {}

  editCurrentUserEmail(newEmail: string) {
    return this.http.post<{ jwt: string }>(`${this.apiUrl}/edit-user-email`, { newEmail });
  }

  editCurrentUserPassword(oldPassword: string, newPassword: string) {
    return this.http.post<postEditUserPassword>(`${this.apiUrl}/edit-user-password`, {
      oldPassword,
      newPassword,
    });
  }

  currentUserTickets() {
    return this.http.get<getUserBoughtTicketDto[]>(`${this.apiUrl}/user-tickets`)
    .pipe(resiliencePipe());
  }
}
