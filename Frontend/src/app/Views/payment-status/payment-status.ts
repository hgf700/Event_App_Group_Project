import { ChangeDetectorRef, Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { PaymentService } from '../../Services/PaymentService';
import { Subscription } from 'rxjs';
import { StatesOfTicket } from '../../Enum/StatesOfTicket';

@Component({
selector: 'app-payment-status',
standalone: true,
imports: [CommonModule, RouterModule],
templateUrl: './payment-status.html',
styleUrl: './payment-status.css',
})
export class PaymentStatus implements OnInit, OnDestroy {
readonly StatesOfTicket = StatesOfTicket;

paymentId: number | null = null;
loading = true;
paymentState: StatesOfTicket | null = null;
error = false;
cancelled = false;

private readonly maxAttempts = 50;
private attempt = 0;
private timeoutId: ReturnType<typeof setTimeout> | null = null;
private statusSub?: Subscription;

constructor(
private paymentService: PaymentService,
private route: ActivatedRoute,
private router: Router,
private cdr: ChangeDetectorRef,
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

if (this.cancelled) {
  this.paymentState = StatesOfTicket.Cancelled;
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
      // Backend zwraca numeryczny enum.
      this.paymentState = Number(res.state) as StatesOfTicket;
      this.attempt++;

      if (this.paymentState === StatesOfTicket.Paid) {
        this.loading = false;
        this.error = false;
        this.cdr.detectChanges();
        return;
      }

      if (
        this.paymentState === StatesOfTicket.Expired ||
        this.paymentState === StatesOfTicket.Cancelled ||
        this.paymentState === StatesOfTicket.Refunded
      ) {
        this.loading = false;
        this.error = false;
        this.cdr.detectChanges();
        return;
      }

      if (this.attempt >= this.maxAttempts) {
        this.loading = false;
        this.error = true;
        this.cdr.detectChanges();
        return;
      }

      this.timeoutId = setTimeout(() => {
        this.checkPaymentStatus();
      }, 1500);
    },

    error: (err) => {
      console.error(
        'Nie udało się pobrać statusu płatności:',
        err,
      );

      this.finishWithError();
    },
  });

}

private finishWithError(): void {
this.loading = false;
this.error = true;
this.cdr.detectChanges();
}

returnToEvents(): void {
this.router.navigate(['/get-events']);
}

ngOnDestroy(): void {
if (this.timeoutId !== null) {
clearTimeout(this.timeoutId);
}

this.statusSub?.unsubscribe();

}
}
