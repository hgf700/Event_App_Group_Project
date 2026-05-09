import { Component, OnInit, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';
import { ChangeDetectorRef } from '@angular/core';
import { EventService } from '../../Services/EventService';
import { PaymentService } from '../../Services/PaymentService';
import { eventDto } from '../../Dto/getEventDto';

@Component({
  selector: 'app-sub-event-details',
  standalone: true,
  imports: [CommonModule, MatDialogModule, FormsModule],
  templateUrl: './sub-event-details.html',
  styleUrl: './sub-event-details.css',
})
export class SubEventDetails implements OnInit {
  event?: eventDto;
  loading = false;
  eventId!: number;

  constructor(
    private cdr: ChangeDetectorRef,
    @Inject(MAT_DIALOG_DATA) public data: { eventId: number },
    private dialogRef: MatDialogRef<SubEventDetails>,
    private eventService: EventService,
    private paymentService: PaymentService,
  ) {}

  ngOnInit(): void {
    this.eventId = this.data.eventId;
    this.getEventDetails();
  }

  getEventDetails() {
    this.loading = true;
    this.eventService.eventDetails(this.eventId).subscribe({
      next: (data) => {
        this.event = data;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się getEvents');
      },
    });
  }

  buyTicket(eventId: number) {
    this.loading = true;
    this.paymentService.buyTicketPaymentProcess(eventId).subscribe({
      next: (res) => {
        this.loading = true;
        window.location.href = res.url;
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się buyTicket');
      },
    });
  }
}
