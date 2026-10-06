import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

export interface BuyTicketResponse {
  url: string;
  paymentId: number;
}

export interface PaymentStatusResponse {
  id: number;
  state: 'Pending' | 'Paid' | 'Cancelled' | 'Expired' | 'Refunded';
  createdAt: string;
  paidAt: string | null;
}

@Injectable({ providedIn: 'root' })
export class PaymentService {
  private readonly apiUrl = 'https://localhost:7051/api/payment';

  constructor(private http: HttpClient) {}

  /**
   * Tworzy sesję Stripe Checkout i zwraca URL do przekierowania.
   * Backend: POST /api/Payment/buy-ticket/{eventId}
   */
  buyTicket(eventId: number): Observable<BuyTicketResponse> {
    return this.http.post<BuyTicketResponse>(
      `${this.apiUrl}/buy-ticket/${eventId}`,
      {}
    );
  }

  /**
   * Pobiera aktualny status płatności.
   * Backend: GET /api/Payment/status/{paymentId}
   */
  getPaymentStatus(paymentId: number): Observable<PaymentStatusResponse> {
    return this.http.get<PaymentStatusResponse>(
      `${this.apiUrl}/status/${paymentId}`
    );
  }

  /**
   * Anuluje oczekującą płatność (Pending).
   * Wymaga endpointu CancelPendingPaymentAsync w backendzie.
   * Backend: POST /api/Payment/cancel/{paymentId}
   */
  cancelPendingPayment(paymentId: number): Observable<void> {
    return this.http.post<void>(
      `${this.apiUrl}/cancel/${paymentId}`,
      {}
    );
  }
}