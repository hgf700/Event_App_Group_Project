import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';
import { getAppUsageInfoDto } from '../Dto/getAppUsageInfoDto';
import { getAdminUserDto } from '../Dto/getAdminUserDto';
import { getBoughtTicketDto } from '../Dto/getBoughtTicketDto';
import { getEventAdminDto } from '../Dto/getEventAdminDto';

@Injectable({ providedIn: 'root' })
export class AdminService {
  private apiUrl = 'https://localhost:7051/api/v1/admin';

  constructor(private http: HttpClient) {}

  seedDataBase() {
    return this.http.post<boolean>(
      `${this.apiUrl}/admin-seed-database`, {}
    );
  }

  getAppUsageInfo() {
    return this.http.get<getAppUsageInfoDto>(
      `${this.apiUrl}/admin-app-usage-info`
    );
  }

  getEvents() {
    return this.http.get<getEventAdminDto[]>(
      `${this.apiUrl}/admin-events`
    );
  }

  deleteEvent(id: number) {
    return this.http.post<void>(
      `${this.apiUrl}/admin-delete-event/${id}`,
      {}
    );
  }

  getUsers() {
    return this.http.get<getAdminUserDto[]>(
      `${this.apiUrl}/admin-users`
    );
  }

  searchUser(id: string) {
    return this.http.get<getAdminUserDto>(
      `${this.apiUrl}/admin-search-user/${id}`
    );
  }

  deleteUser(id: string) {
    return this.http.post<void>(
      `${this.apiUrl}/admin-delete-user/${id}`,
      {}
    );
  }

  blockUser(id: string) {
    return this.http.post<void>(
      `${this.apiUrl}/admin-block-user/${id}`,
      {}
    );
  }

  getBlockedUsers() {
    return this.http.get<getAdminUserDto[]>(
      `${this.apiUrl}/admin-blocked-users`
    );
  }

  unblockUser(id: string) {
    return this.http.post<void>(
      `${this.apiUrl}/admin-unblock-user/${id}`,
      {}
    );
  }

  getBoughtTickets() {
    return this.http.get<getBoughtTicketDto[]>(
      `${this.apiUrl}/admin-bought-tickets`
    );
  }
}