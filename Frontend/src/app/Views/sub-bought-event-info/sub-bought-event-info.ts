import { Component, OnInit, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';
import { ChangeDetectorRef } from '@angular/core';
import { EventService } from '../../Services/EventService';
import { PaymentService } from '../../Services/PaymentService';
import { getEventDto } from '../../Dto/getEventDto';

@Component({
  selector: 'app-sub-bought-event-info',
  standalone: true,
  imports: [],
  templateUrl: './sub-bought-event-info.html',
  styleUrl: './sub-bought-event-info.css',
})
export class SubBoughtEventInfo implements OnInit{
  loading = false;
  
  constructor(){}

  ngOnInit(): void {
    // this.getUserTickets();
  }
}
