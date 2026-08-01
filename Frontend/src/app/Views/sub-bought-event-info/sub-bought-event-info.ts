import { Component, OnInit, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';
import { ChangeDetectorRef } from '@angular/core';
import { EventService } from '../../Services/EventService';
import { PaymentService } from '../../Services/PaymentService';
import { getEventTicketWithQrDto } from '../../Dto/getEventQrCodeInfoDto';

@Component({
  selector: 'app-sub-bought-event-info',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './sub-bought-event-info.html',
  styleUrl: './sub-bought-event-info.css',
})
export class SubBoughtEventInfo implements OnInit{
  loading = false;
  event?: getEventTicketWithQrDto;
  eventId!: number;
  
  constructor(
    private cdr: ChangeDetectorRef,
    @Inject(MAT_DIALOG_DATA) public data: { eventId: number },
    private dialogRef: MatDialogRef<SubBoughtEventInfo>,
    private eventService: EventService,
  ){}

  ngOnInit(): void {
    this.eventId = this.data.eventId;
    this.getBoughtTicketDetails();
  }

  getBoughtTicketDetails() {
    this.loading = true;
    this.eventService.getTicketsWithQr(this.eventId).subscribe({
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
}
