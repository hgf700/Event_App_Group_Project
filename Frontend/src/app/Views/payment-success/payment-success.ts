import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { PaymentService } from '../../Services/PaymentService'

@Component({
  selector: 'app-payment-success',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './payment-success.html',
  styleUrl: './payment-success.css',
})
export class PaymentSuccess implements OnInit {
  id!: number;

  constructor(
    private paymentService: PaymentService,
    private route: ActivatedRoute,
    private router: Router,
  ){}

  ngOnInit(): void {
    this.id = Number(this.route.snapshot.queryParamMap.get('id'));
    console.log(this.id);
    this.paymentSuccess();
  }

  paymentSuccess(){
    this.paymentService.paymentProcessSuccess(this.id)
    .subscribe({
      next: () => {
        console.log("Payment success");
      },
      error: (err) => {
        console.error(err);
      }
    });
  }

  returnToEvents() {
    this.router.navigate(['/get-events']);
  }
}
