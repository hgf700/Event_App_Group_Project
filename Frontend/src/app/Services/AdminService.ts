import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { authResponseDto } from '../Dto/authResponseDto';
import { getAppUsageInfoDto } from '../Dto/getAppUsageInfoDto';
import { getAdminUserDto } from '../Dto/getAdminUserDto';
import { getBoughtTicketDto } from '../Dto/getBoughtTicketDto';

@Injectable({ providedIn: 'root' })
export class AdminService {
  private apiUrl = 'https://localhost:7051/api/v1/admin';

  constructor(private http: HttpClient) {}

  seedDataBase() {
    return this.http.post<boolean>(
      `${this.apiUrl}/admin-seed-database`, {}
    );
  }

  appUsageInfo() {
    return this.http.get<getAppUsageInfoDto>(
      `${this.apiUrl}/admin-app-usage-info`,
    )
  }

  adminAllEvents() {
    return this.http.get<getAppUsageInfoDto>(
      `${this.apiUrl}/admin-events`,
    )
  }

  adminDeleteEvent(id: number) {
    return this.http.post<number>(
      `${this.apiUrl}/admin-delete-event/${id}`,
      {}
    );
  }

  adminAllUsers() {
    return this.http.get<getAdminUserDto>(
      `${this.apiUrl}/admin-users`,
    )
  }

  adminSearchUser(id: string) {
    return this.http.get<string>(
      `${this.apiUrl}/admin-search-user/${id}`,
    )
  }

  adminDeleteUser(id: number) {
    return this.http.post<number>(
      `${this.apiUrl}/admin-delete-user/${id}`,
      {}
    );
  }
  
  adminBlockUser(id: string) {
    return this.http.post<string>(
      `${this.apiUrl}/admin-block-user/${id}`,
      {}
    );
  }

  adminBlockedUsers() {
    return this.http.get(
      `${this.apiUrl}/admin-blocked-users`,
    )
  }

  adminUnBlockUser(id: string) {
    return this.http.post<string>(
      `${this.apiUrl}/admin-unblock-user/${id}`,
      {}
    );
  }

  adminBoughtTickets() {
    return this.http.get<getBoughtTicketDto>(
      `${this.apiUrl}/admin-blocked-users`,
    )
  }
}