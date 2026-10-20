// user.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { UserService } from '../Services/UserService';
import { postEditUserPassword } from '../Dto/postEditUserPassword';
import { getUserBoughtTicketDto } from '../Dto/getUserBoughtTicketDto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('UserService', () => {
  let service: UserService;
  let httpMock: HttpTestingController;

  const apiUrl = 'https://localhost:7051/api/v1/user';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [UserService, provideHttpClient(), provideHttpClientTesting()],
    });

    service = TestBed.inject(UserService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ========== editCurrentUserEmail ==========
  describe('editCurrentUserEmail', () => {
    it('should send POST request with newEmail', () => {
      const newEmail = 'nowy@email.com';
      const mockResponse = { jwt: 'new-jwt-token' };

      service.editCurrentUserEmail(newEmail).subscribe((res) => {
        expect(res).toEqual(mockResponse);
        expect(res.jwt).toBe('new-jwt-token');
      });

      const req = httpMock.expectOne(`${apiUrl}/edit-user-email`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ newEmail });

      req.flush(mockResponse);
    });

    it('should handle error when email update fails', () => {
      const newEmail = 'taken@email.com';

      service.editCurrentUserEmail(newEmail).subscribe({
        next: () => {
          throw new Error('should have failed');
        },
        error: (err) => {
          expect(err.status).toBe(400);
        },
      });

      const req = httpMock.expectOne(`${apiUrl}/edit-user-email`);
      expect(req.request.method).toBe('POST');

      req.flush('Email already taken', {
        status: 400,
        statusText: 'Bad Request',
      });
    });
  });

  // ========== editCurrentUserPassword ==========
  describe('editCurrentUserPassword', () => {
    it('should send POST request with oldPassword and newPassword', () => {
      const oldPassword = 'stareHaslo123';
      const newPassword = 'noweHaslo456';

      // response type w serwisie to postEditUserPassword (mimo że to raczej request DTO)
      const mockResponse: postEditUserPassword = {
        oldPassword,
        newPassword,
      };

      service.editCurrentUserPassword(oldPassword, newPassword).subscribe((res) => {
        expect(res).toEqual(mockResponse);
      });

      const req = httpMock.expectOne(`${apiUrl}/edit-user-password`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        oldPassword,
        newPassword,
      });

      req.flush(mockResponse);
    });

    it('should handle error when password update fails', () => {
      service.editCurrentUserPassword('wrongOld', 'newPass').subscribe({
        next: () => {
          throw new Error('should have failed');
        },
        error: (err) => {
          expect(err.status).toBe(400);
        },
      });

      const req = httpMock.expectOne(`${apiUrl}/edit-user-password`);
      expect(req.request.method).toBe('POST');

      req.flush('Invalid old password', {
        status: 400,
        statusText: 'Bad Request',
      });
    });
  });

  // ========== currentUserTickets ==========
  describe('currentUserTickets', () => {
    it('should send GET request and return list of tickets', () => {
      const mockTickets: getUserBoughtTicketDto[] = [
        {
          eventId: 1,
          typeOfEvent: 'Koncert',
          nameOfEvent: 'Rock Night',
          startOfEvent: new Date('2026-11-15T20:00:00'),
          address: 'ul. Przykładowa 1',
          city: 'Warszawa',
          nameOfClub: 'Progresja',
        },
        {
          eventId: 2,
          typeOfEvent: 'Teatr',
          nameOfEvent: 'Hamlet',
          startOfEvent: new Date('2026-12-01T19:00:00'),
          address: 'ul. Teatralna 5',
          city: 'Kraków',
          nameOfClub: 'Teatr Stary',
        },
      ];

      service.currentUserTickets().subscribe((res) => {
        expect(res).toEqual(mockTickets);
        expect(res.length).toBe(2);
        expect(res[0].eventId).toBe(1);
        expect(res[0].nameOfEvent).toBe('Rock Night');
      });

      const req = httpMock.expectOne(`${apiUrl}/user-tickets`);
      expect(req.request.method).toBe('GET');

      req.flush(mockTickets);
    });

    it('should return empty array when user has no tickets', () => {
      service.currentUserTickets().subscribe((res) => {
        expect(res).toEqual([]);
      });

      const req = httpMock.expectOne(`${apiUrl}/user-tickets`);
      expect(req.request.method).toBe('GET');

      req.flush([]);
    });
  });
});
