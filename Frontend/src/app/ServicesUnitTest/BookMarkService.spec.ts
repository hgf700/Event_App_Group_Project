// bookmark.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { getBookmarkDto } from '../Dto/getBookmarkDto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { BookMarkService } from '../Services/BookMarkService';

describe('BookMarkService', () => {
  let service: BookMarkService;
  let httpMock: HttpTestingController;

  const apiUrl = 'https://localhost:7051/api/v1/bookmark';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [BookMarkService, provideHttpClient(), provideHttpClientTesting()],
    });

    service = TestBed.inject(BookMarkService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ========== getUserBookmarks ==========
  describe('getUserBookmarks', () => {
    it('should send GET request and return list of bookmarks', () => {
      const mockBookmarks: getBookmarkDto[] = [
        {
          // dostosuj pola do swojego DTO
          eventId: 1,
          eventName: 'Test Event',
        } as getBookmarkDto,
        {
          eventId: 2,
          eventName: 'Another Event',
        } as getBookmarkDto,
      ];

      service.getUserBookmarks().subscribe((res) => {
        expect(res).toEqual(mockBookmarks);
        expect(res.length).toBe(2);
      });

      const req = httpMock.expectOne(`${apiUrl}/user-bookmarks`);
      expect(req.request.method).toBe('GET');

      req.flush(mockBookmarks);
    });

    it('should return empty array when user has no bookmarks', () => {
      service.getUserBookmarks().subscribe((res) => {
        expect(res).toEqual([]);
      });

      const req = httpMock.expectOne(`${apiUrl}/user-bookmarks`);
      expect(req.request.method).toBe('GET');

      req.flush([]);
    });
  });

  // ========== bookmarkEvent ==========
  describe('bookmarkEvent', () => {
    it('should send POST request to bookmark-event endpoint', () => {
      const eventId = 42;

      service.bookmarkEvent(eventId).subscribe((res) => {
        expect(res).toBeTruthy();
      });

      const req = httpMock.expectOne(`${apiUrl}/bookmark-event/${eventId}`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});

      req.flush({}); // sukces
    });

    it('should handle error when bookmark fails', () => {
      const eventId = 99;

      service.bookmarkEvent(eventId).subscribe({
        next: () => fail('should have failed'),
        error: (err) => {
          expect(err.status).toBe(400);
        },
      });

      const req = httpMock.expectOne(`${apiUrl}/bookmark-event/${eventId}`);
      expect(req.request.method).toBe('POST');

      req.flush('Bad Request', {
        status: 400,
        statusText: 'Bad Request',
      });
    });
  });

  // ========== unBookmarkEvent ==========
  describe('unBookmarkEvent', () => {
    it('should send POST request to unbookmark-event endpoint', () => {
      const eventId = 42;

      service.unBookmarkEvent(eventId).subscribe((res) => {
        expect(res).toBeTruthy();
      });

      const req = httpMock.expectOne(`${apiUrl}/unbookmark-event/${eventId}`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});

      req.flush({}); // sukces
    });

    it('should handle error when unbookmark fails', () => {
      const eventId = 99;

      service.unBookmarkEvent(eventId).subscribe({
        next: () => fail('should have failed'),
        error: (err) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne(`${apiUrl}/unbookmark-event/${eventId}`);
      expect(req.request.method).toBe('POST');

      req.flush('Not Found', {
        status: 404,
        statusText: 'Not Found',
      });
    });
  });
});

function fail(arg0: string): void {
  throw new Error('Function not implemented.');
}
