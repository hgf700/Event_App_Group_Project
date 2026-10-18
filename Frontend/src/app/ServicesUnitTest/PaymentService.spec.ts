// payment.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { PaymentService, PaymentStatusResponse } from '../Services/PaymentService';
import { postBuyTicketResponseDto } from '../Dto/postBuyTicketResponseDto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('PaymentService', () => {
  let service: PaymentService;
  let httpMock: HttpTestingController;

  const apiUrl = 'https://localhost:7051/api/v1/payments';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        PaymentService,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(PaymentService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ========== buyTicket ==========
  describe('buyTicket', () => {
    it('should send POST request to buy-ticket endpoint', () => {
      const eventId = 42;
      const mockResponse = {
          checkoutUrl: 'https://checkout.stripe.com/session/xxx',
          paymentId: 123,
      } as unknown as postBuyTicketResponseDto;

      service.buyTicket(eventId).subscribe((res) => {
        expect(res).toEqual(mockResponse);
      });

      const req = httpMock.expectOne(`${apiUrl}/buy-ticket/${eventId}`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});

      req.flush(mockResponse);
    });

    it('should handle error when buyTicket fails', () => {
      const eventId = 99;

      service.buyTicket(eventId).subscribe({
        next: () => {
          throw new Error('should have failed');
        },
        error: (err) => {
          expect(err.status).toBe(400);
        },
      });

      const req = httpMock.expectOne(`${apiUrl}/buy-ticket/${eventId}`);
      expect(req.request.method).toBe('POST');

      req.flush('Bad Request', {
        status: 400,
        statusText: 'Bad Request',
      });
    });
  });

  // ========== getPaymentStatus ==========
  describe('getPaymentStatus', () => {
    it('should send GET request and return payment status', () => {
      const paymentId = 123;
      const mockStatus: PaymentStatusResponse = {
        id: paymentId,
        state: 'Paid',
        createdAt: '2026-10-18T10:00:00Z',
        paidAt: '2026-10-18T10:05:00Z',
      };

      service.getPaymentStatus(paymentId).subscribe((res) => {
        expect(res).toEqual(mockStatus);
        expect(res.state).toBe('Paid');
        expect(res.id).toBe(paymentId);
      });

      const req = httpMock.expectOne(`${apiUrl}/status/${paymentId}`);
      expect(req.request.method).toBe('GET');

      req.flush(mockStatus);
    });

    it('should return Pending status correctly', () => {
      const paymentId = 456;
      const mockStatus: PaymentStatusResponse = {
        id: paymentId,
        state: 'Pending',
        createdAt: '2026-10-18T11:00:00Z',
        paidAt: null,
      };

      service.getPaymentStatus(paymentId).subscribe((res) => {
        expect(res.state).toBe('Pending');
        expect(res.paidAt).toBeNull();
      });

      const req = httpMock.expectOne(`${apiUrl}/status/${paymentId}`);
      expect(req.request.method).toBe('GET');

      req.flush(mockStatus);
    });
  });

  // ========== cancelPendingPayment ==========
  describe('cancelPendingPayment', () => {
    it('should send POST request to cancel endpoint', () => {
      const paymentId = 123;

      service.cancelPendingPayment(paymentId).subscribe((res) => {
        expect(res).toBeNull(); // void response
      });

      const req = httpMock.expectOne(`${apiUrl}/cancel/${paymentId}`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});

      req.flush(null);
    });

    it('should handle error when cancel fails', () => {
      const paymentId = 999;

      service.cancelPendingPayment(paymentId).subscribe({
        next: () => {
          throw new Error('should have failed');
        },
        error: (err) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne(`${apiUrl}/cancel/${paymentId}`);
      expect(req.request.method).toBe('POST');

      req.flush('Not Found', {
        status: 404,
        statusText: 'Not Found',
      });
    });
  });
});