import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-payment-success',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './payment-success.html',
  styleUrl: './payment-success.css',
})
export class PaymentSuccess implements OnInit {

  constructor(
    private route: ActivatedRoute,
  ){}


  ngOnInit(): void {
    const id = this.route.snapshot.queryParamMap.get('id');
    console.log(id);
  }
}
