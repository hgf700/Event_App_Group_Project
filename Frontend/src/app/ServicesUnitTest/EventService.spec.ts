// event.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { paginatedResponse } from '../model/paginatedResponse';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventService } from '../Services/EventService';
import { getEventDto } from '../Dto/getEventDto';
import { getEventTicketWithQrDto } from '../Dto/getEventQrCodeInfoDto';

describe('EventService', () => {
  let service: EventService;
  let httpMock: HttpTestingController;

  const apiUrl = 'https://localhost:7051/api/v1/event';
  const apiUserTicketUrl = 'https://localhost:7051/api/v1/user-ticket';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [EventService, provideHttpClient(), provideHttpClientTesting()],
    });

    service = TestBed.inject(EventService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ========== getEvents ==========
  describe('getEvents', () => {
    it('should send GET request with page and pageSize', () => {
      const mockResponse = {
        data: [{ eventId: 1, nameOfEvent: 'Event 1' } as getEventDto],
        totalCount: 1,
      } as paginatedResponse<getEventDto>;

      service.getEvents(1, 10).subscribe((res) => {
        expect(res).toEqual(mockResponse);
        expect(res.data.length).toBe(1);
      });

      const req = httpMock.expectOne(`${apiUrl}/get-events?page=1&pageSize=10`);
      expect(req.request.method).toBe('GET');

      req.flush(mockResponse);
    });
  });

  // ========== eventDetails ==========
  describe('eventDetails', () => {
    it('should send GET request with eventId', () => {
      const eventId = 42;
      const mockEvent = {
        eventId: eventId,
        nameOfEvent: 'Test Event',
      } as getEventDto;

      service.eventDetails(eventId).subscribe((res) => {
        expect(res).toEqual(mockEvent);
        expect(res.eventId).toBe(eventId);
      });

      const req = httpMock.expectOne(`${apiUrl}/event-details/${eventId}`);
      expect(req.request.method).toBe('GET');

      req.flush(mockEvent);
    });
  });

  // ========== getTicketsWithQr ==========
  describe('getTicketsWithQr', () => {
    it('should send GET request to user-ticket endpoint', () => {
      const eventId = 15;
      const mockTicket = {
        eventId,
        qrCode: 'base64-qr-code',
      } as getEventTicketWithQrDto;

      service.getTicketsWithQr(eventId).subscribe((res) => {
        expect(res).toEqual(mockTicket);
      });

      const req = httpMock.expectOne(`${apiUserTicketUrl}/ticket-detail-with-qr/${eventId}`);
      expect(req.request.method).toBe('GET');

      req.flush(mockTicket);
    });
  });

  // ========== getPublicEvents ==========
  describe('getPublicEvents', () => {
    it('should send GET request with page and pageSize', () => {
      const mockResponse = {
        data: [{ eventId: 5, nameOfEvent: 'Public Event' } as getEventDto],
        totalCount: 1,
      } as paginatedResponse<getEventDto>;

      service.getPublicEvents(2, 20).subscribe((res) => {
        expect(res).toEqual(mockResponse);
      });

      const req = httpMock.expectOne(`${apiUrl}/public-get-events?page=2&pageSize=20`);
      expect(req.request.method).toBe('GET');

      req.flush(mockResponse);
    });
  });

  // ========== searchOrDownloadEventForm ==========
  describe('searchOrDownloadEventForm', () => {
    it('should send POST request with city in body', () => {
      const city = 'Warszawa';
      const mockEvents: getEventDto[] = [
        { eventId: 1, nameOfEvent: 'Event in Warsaw' } as getEventDto,
      ];

      service.searchOrDownloadEventForm(city).subscribe((res) => {
        expect(res).toEqual(mockEvents);
        expect(res.length).toBe(1);
      });

      const req = httpMock.expectOne(`${apiUrl}/search-event-and-download`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ city });

      req.flush(mockEvents);
    });
  });

  // ========== searchOrDownloadEventQuery ==========
  describe('searchOrDownloadEventQuery', () => {
    it('should send POST request with city as query param', () => {
      const city = 'Kraków';
      const mockEvents: getEventDto[] = [
        { eventId: 2, nameOfEvent: 'Event in Krakow' } as getEventDto,
      ];

      service.searchOrDownloadEventQuery(city).subscribe((res) => {
        expect(res).toEqual(mockEvents);
      });

      const req = httpMock.expectOne(
        (request) =>
          request.url === `${apiUrl}/search-event-and-download` &&
          request.params.get('city') === city,
      );

      expect(req.request.method).toBe('POST');
      expect(req.request.body).toBeNull();
      expect(req.request.params.get('city')).toBe(city);

      req.flush(mockEvents);
    });
  });
});
