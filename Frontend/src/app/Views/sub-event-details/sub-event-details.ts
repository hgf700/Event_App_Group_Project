import { Component, OnInit, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  MAT_DIALOG_DATA,
  MatDialogRef,
  MatDialogModule,
} from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';

type ViewMode = 'list' | 'create';

@Component({
  selector: 'app-sub-event-details',
  standalone: true,
  imports: [CommonModule, MatDialogModule, FormsModule],
  templateUrl: './sub-event-details.html',
  styleUrl: './sub-event-details.css',
})
export class SubEventDetails implements OnInit{
  viewMode: ViewMode = 'list';
  loading = false;

  eventId!: number;

  constructor(
    @Inject(MAT_DIALOG_DATA) public data: { eventId: number },
    private dialogRef: MatDialogRef<SubEventDetails>,
) {}

  ngOnInit(): void {
    this.eventId = this.data.eventId;
  }
}
