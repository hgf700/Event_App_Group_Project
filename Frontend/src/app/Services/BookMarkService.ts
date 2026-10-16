import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getEventDto } from '../Dto/getEventDto';
import { paginatedResponse } from '../model/paginatedResponse';
import { getEventTicketWithQrDto } from '../Dto/getEventQrCodeInfoDto';
import { getBookmarkDto } from '../Dto/getBookmarkDto';

@Injectable({ providedIn: 'root' })
export class BookMarkService {
  private apiUrl = 'https://localhost:7051/api/v1/bookmark';

  constructor(private http: HttpClient) {}

  getUserBookmarks() {
    return this.http.get<getBookmarkDto[]>(`${this.apiUrl}/user-bookmarks`);
  }

  bookmarkEvent(eventId: number) {
    return this.http.post(`${this.apiUrl}/bookmark-event/${eventId}`, {});
  }

  unBookmarkEvent(eventId: number) {
    return this.http.post(`${this.apiUrl}/unbookmark-event/${eventId}`, {});
  }
}
