import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { PaymentService } from '../../Services/PaymentService';

@Component({
  selector: 'app-payment-failed',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './payment-failed.html',
  styleUrl: './payment-failed.css',
})
export class PaymentFailed implements OnInit {
  constructor(
    private paymentService: PaymentService,
    private route: ActivatedRoute,
    private router: Router,
  ) {}

  ngOnInit(): void {
    this.paymentSuccess();
  }

  paymentSuccess() {
    this.paymentService.paymentProcessFailed().subscribe({
      next: () => {
        console.log('paymentProcessFailed');
      },
      error: (err) => {
        console.error(err);
      },
    });
  }

  returnToEvents() {
    this.router.navigate(['/get-events']);
  }
}
