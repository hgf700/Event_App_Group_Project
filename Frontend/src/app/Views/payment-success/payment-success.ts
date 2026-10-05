import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { PaymentService } from '../../Services/PaymentService';

@Component({
  selector: 'app-payment-success',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './payment-success.html',
  styleUrl: './payment-success.css',
})
export class PaymentSuccess implements OnInit {
  paymentId: number | null = null;
  loading = true;
  paymentState = '';
  error = false;

  constructor(
    private paymentService: PaymentService,
    private route: ActivatedRoute,
    private router: Router,
  ) {}

  ngOnInit(): void {
    const paymentIdParam = this.route.snapshot.queryParamMap.get('paymentId');

    if (!paymentIdParam) {
      console.error('Brak paymentId');
      this.loading = false;
      this.error = true;
      return;
    }

    const paymentId = Number(paymentIdParam);

    if (!Number.isInteger(paymentId) || paymentId <= 0) {
      console.error('Nieprawidłowe paymentId:', paymentIdParam);
      this.loading = false;
      this.error = true;
      return;
    }

    this.paymentId = paymentId;

    this.checkPaymentStatus();
  }

  checkPaymentStatus(): void {
    if (this.paymentId === null) {
      return;
    }

    this.paymentService.getPaymentStatus(this.paymentId).subscribe({
        next: (res) => {
          console.log('Payment status:', res);

          this.paymentState = res.state;

          if (res.state === 'Paid') {
            this.loading = false;
            return;
          }

          if (res.state === 'Expired' || res.state === 'Cancelled' || res.state === 'Refunded') {
            this.loading = false;
            return;
          }

          // Nadal Pending.  Stripe webhook może jeszcze nie zdążyć zmienić statusu.
          setTimeout(() => {
            this.checkPaymentStatus();
          }, 1500);
        },

        error: (err) => {
          console.error('Nie udało się pobrać statusu płatności:', err);

          this.loading = false;
          this.error = true;
        },
      });
  }

  returnToEvents(): void {
    this.router.navigate(['/get-events']);
  }
}