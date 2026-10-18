import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { HttpClient, provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AdminService } from '../Services/AdminService';
import { getAppUsageInfoDto } from '../Dto/getAppUsageInfoDto';
import { getEventAdminDto } from '../Dto/getEventAdminDto';
import { getAdminUserDto } from '../Dto/getAdminUserDto';
import { getBoughtTicketDto } from '../Dto/getBoughtTicketDto';
import { getBookmarkDto } from '../Dto/getBookmarkDto';
import { StatesOfTicket } from '../Enum/StatesOfTicket';
import { TicketState } from '../Enum/TicketState';

describe('AdminService', () => {
  let service: AdminService;
  let httpMock: HttpTestingController;

  const apiUrl = 'https://localhost:7051/api/v1/admin';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        AdminService,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(AdminService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ─────────────────────────────────────────────
  // seedDataBase
  // ─────────────────────────────────────────────

  it('seedDataBase should POST and return boolean', () => {
    let result: boolean | undefined;

    service.seedDataBase().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-seed-database`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});

    req.flush(false);

    expect(result).toBe(false);
  });

  // ─────────────────────────────────────────────
  // getAppUsageInfo
  // ─────────────────────────────────────────────

  it('getAppUsageInfo should GET usage info', () => {
    const mock: getAppUsageInfoDto = {
      activeUserCount: 10,
      boughtTickets: 5,
      activeTickets: 3,
    };

    let result: getAppUsageInfoDto | undefined;

    service.getAppUsageInfo().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-app-usage-info`);
    expect(req.request.method).toBe('GET');

    req.flush(mock);

    expect(result).toEqual(mock);
  });

  // ─────────────────────────────────────────────
  // getEvents
  // ─────────────────────────────────────────────

  it('getEvents should GET events list', () => {
    const mock: getEventAdminDto[] = [
      {
        id: 1,
        nameOfEvent: 'Concert',
        startOfEvent: '2026-12-01T20:00:00Z',
        city: 'Warszawa',
        nameOfClub: 'Club 1',
      },
    ];

    let result: getEventAdminDto[] | undefined;

    service.getEvents().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-events`);
    expect(req.request.method).toBe('GET');

    req.flush(mock);

    expect(result).toEqual(mock);
    expect(result!.length).toBe(1);
  });

  // ─────────────────────────────────────────────
  // deleteEvent
  // ─────────────────────────────────────────────

  it('deleteEvent should POST with event id', () => {
    let completed = false;

    service.deleteEvent(42).subscribe(() => {
      completed = true;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-delete-event/42`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});

    req.flush(null);

    expect(completed).toBe(true);
  });

  // ─────────────────────────────────────────────
  // getUsers
  // ─────────────────────────────────────────────

  it('getUsers should GET users list', () => {
    const mock: getAdminUserDto[] = [
      {
        id: 'u1',
        email: 'user@test.com',
        userName: 'user@test.com',
        roles: ['user'],
      },
    ];

    let result: getAdminUserDto[] | undefined;

    service.getUsers().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-users`);
    expect(req.request.method).toBe('GET');

    req.flush(mock);

    expect(result).toEqual(mock);
  });

  // ─────────────────────────────────────────────
  // deleteUser
  // ─────────────────────────────────────────────

  it('deleteUser should POST with user id', () => {
    let completed = false;

    service.deleteUser('user-123').subscribe(() => {
      completed = true;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-delete-user/user-123`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});

    req.flush(null);

    expect(completed).toBe(true);
  });

  // ─────────────────────────────────────────────
  // blockUser
  // ─────────────────────────────────────────────

  it('blockUser should POST with user id', () => {
    let completed = false;

    service.blockUser('user-456').subscribe(() => {
      completed = true;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-block-user/user-456`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});

    req.flush(null);

    expect(completed).toBe(true);
  });

  // ─────────────────────────────────────────────
  // getBlockedUsers
  // ─────────────────────────────────────────────

  it('getBlockedUsers should GET blocked users', () => {
    const mock: getAdminUserDto[] = [
      {
        id: 'b1',
        email: 'blocked@test.com',
        userName: 'blocked@test.com',
        roles: ['user'],
      },
    ];

    let result: getAdminUserDto[] | undefined;

    service.getBlockedUsers().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-blocked-users`);
    expect(req.request.method).toBe('GET');

    req.flush(mock);

    expect(result).toEqual(mock);
  });

  // ─────────────────────────────────────────────
  // unblockUser
  // ─────────────────────────────────────────────

  it('unblockUser should POST with user id', () => {
    let completed = false;

    service.unblockUser('user-789').subscribe(() => {
      completed = true;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-unblock-user/user-789`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});

    req.flush(null);

    expect(completed).toBe(true);
  });

  // ─────────────────────────────────────────────
  // getBoughtTickets
  // ─────────────────────────────────────────────

  it('getBoughtTickets should GET tickets list', () => {
    const mock: getBoughtTicketDto[] = [
      {
        userId: 'u1',
        userEmail: 'buyer@test.com',
        eventId: 1,
        eventName: 'Concert',
        eventDate: '2026-12-01T20:00:00Z',
        createdAt: '2026-01-01T12:00:00Z',
        paymentStateAt: '2026-01-01T12:05:00Z',
        paymentState: StatesOfTicket.Paid,
        ticketStateAt: '2026-01-01T12:05:00Z',
        ticketState: TicketState.Active,
        paymentId: 'cs_test_123',
      },
    ];

    let result: getBoughtTicketDto[] | undefined;

    service.getBoughtTickets().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-bought-tickets`);
    expect(req.request.method).toBe('GET');

    req.flush(mock);

    expect(result).toEqual(mock);
    expect(result![0].eventName).toBe('Concert');
  });

  // ─────────────────────────────────────────────
  // adminGetAllBookmarks
  // ─────────────────────────────────────────────

  it('adminGetAllBookmarks should GET bookmarks list', () => {
    const mock: getBookmarkDto[] = [
      {
        id: 1,
        userId: 'u1',
        eventId: 10,
        eventName: 'Festival',
      },
    ];

    let result: getBookmarkDto[] | undefined;

    service.adminGetAllBookmarks().subscribe((res) => {
      result = res;
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-all-bookmarks`);
    expect(req.request.method).toBe('GET');

    req.flush(mock);

    expect(result).toEqual(mock);
  });

  // ─────────────────────────────────────────────
  // error handling
  // ─────────────────────────────────────────────

  it('getEvents should propagate HTTP error', () => {
    let errorStatus: number | undefined;

    service.getEvents().subscribe({
      next: () => {
        throw new Error('should have failed');
      },
      error: (err) => {
        errorStatus = err.status;
      },
    });

    const req = httpMock.expectOne(`${apiUrl}/admin-events`);
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });

    expect(errorStatus).toBe(500);
  });
});