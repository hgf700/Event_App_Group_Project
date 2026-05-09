import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';

@Injectable({ providedIn: 'root' })
export class PaymentService {
  private apiUrl = 'https://localhost:7051/api/v1/Payments';
  private apiUrlCallback = 'https://localhost:7051/api/v1/PaymentCallback';

  constructor(
    private http: HttpClient
  ) {}

  buyTicketPaymentProcess(eventId: number) {
    return this.http.post<{ url: string }>(
      `${this.apiUrl}/buy-ticket/${eventId}`, 
      {},
      {headers: getAuthHeaders()}
    );
  }

  paymentProcessSuccess(eventId: number){
    return this.http.post<{ eventId: number }>(
      `${this.apiUrlCallback}/payment-success/${eventId}`, 
      {},
      {headers: getAuthHeaders()}
    );
  }

  paymentProcessFailed(){
    return this.http.post(
      `${this.apiUrlCallback}/payment-failed`, 
      {},
      {headers: getAuthHeaders()}
    );
  }
}