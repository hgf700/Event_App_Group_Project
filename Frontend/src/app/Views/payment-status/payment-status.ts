import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { PaymentService } from '../../Services/PaymentService';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-payment-status',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './payment-status.html',
  styleUrl: './payment-status.css',
})
export class PaymentStatus implements OnInit, OnDestroy {
  paymentId: number | null = null;
  loading = true;
  paymentState = '';
  error = false;
  cancelled = false;

  private readonly maxAttempts = 20; // ~30 sekund (20 × 1.5s)
  private attempt = 0;
  private timeoutId: ReturnType<typeof setTimeout> | null = null;
  private statusSub?: Subscription;

  constructor(
    private paymentService: PaymentService,
    private route: ActivatedRoute,
    private router: Router,
  ) {}

  ngOnInit(): void {
    const paymentIdParam = this.route.snapshot.queryParamMap.get('paymentId');
    const cancelledParam = this.route.snapshot.queryParamMap.get('cancelled');

    this.cancelled = cancelledParam === 'true';

    if (!paymentIdParam) {
      console.error('Brak paymentId');
      this.finishWithError();
      return;
    }

    const paymentId = Number(paymentIdParam);

    if (!Number.isInteger(paymentId) || paymentId <= 0) {
      console.error('Nieprawidłowe paymentId:', paymentIdParam);
      this.finishWithError();
      return;
    }

    this.paymentId = paymentId;

    /*
     * Użytkownik wrócił przez CancelUrl.
     * Nie musimy czekać na webhook/polling.
     */
    if (this.cancelled) {
      this.paymentState = 'Cancelled';
      this.loading = false;
      return;
    }

    this.checkPaymentStatus();
  }

  private checkPaymentStatus(): void {
    if (this.paymentId === null) {
      return;
    }

    this.statusSub?.unsubscribe();

    this.statusSub = this.paymentService
      .getPaymentStatus(this.paymentId)
      .subscribe({
        next: (res) => {
          this.paymentState = res.state;
          this.attempt++;

          // Sukces
          if (res.state === 'Paid') {
            this.loading = false;
            return;
          }

          // Stany końcowe negatywne
          if (
            res.state === 'Expired' ||
            res.state === 'Cancelled' ||
            res.state === 'Refunded'
          ) {
            this.loading = false;
            return;
          }

          // Nadal Pending – czekamy na webhook
          if (this.attempt >= this.maxAttempts) {
            this.loading = false;
            this.error = true;
            return;
          }

          this.timeoutId = setTimeout(() => {
            this.checkPaymentStatus();
          }, 1500);
        },

        error: (err) => {
          console.error(
            'Nie udało się pobrać statusu płatności:',
            err
          );

          this.finishWithError();
        },
      });
  }

  private finishWithError(): void {
    this.loading = false;
    this.error = true;
  }

  returnToEvents(): void {
    this.router.navigate(['/get-events']);
  }

  ngOnDestroy(): void {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
    }

    this.statusSub?.unsubscribe();
  }
}