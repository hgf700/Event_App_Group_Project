import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { getEventDto } from '../../Dto/getEventDto';
import { postCitySearchDto } from '../../Dto/postCitySearchDto';
import { SearchOrDownloadEventService } from '../../Services/SearchOrDownloadEventService';
import { EventService } from '../../Services/EventService';
import { SubEventDetails } from '../sub-event-details/sub-event-details';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';


@Component({
  selector: 'app-search-and-import-events',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule, MatDialogModule],
  templateUrl: './search-and-import-events.html',
  styleUrl: './search-and-import-events.css',
})

export class SearchAndImportEvents implements OnInit {
  searchAndImportEventsForm!: FormGroup;
  events: getEventDto[] = [];
  cityDto!: postCitySearchDto;
  submitted = false;
  loading = false;

  constructor(
    private fb: FormBuilder,
    private route: ActivatedRoute,
    private cdr: ChangeDetectorRef,
    private searchOrDownloadEventService: SearchOrDownloadEventService,
    private dialog: MatDialog,
  ) {
    this.searchAndImportEventsForm = this.fb.group({
      city: ['', [Validators.required]],
    });
  }

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      const city = params['city'];

      if (city) {
        this.searchAndImportEventsForm.patchValue({
          city: city
        });

        this.search(city);
      }
    });
  }

  eventDetails(eventId: number) {
    const dialogRef = this.dialog.open(SubEventDetails, {
      width: '600px',
      height: '400px',
      data: {
        eventId,
      },
    });

    dialogRef.afterClosed().subscribe((result) => {
      console.log('Dialog closed:', result);
    });
  }
  
  search(city: string) {
    this.searchOrDownloadEventService.searchOrDownloadEventQuery(city)
      .subscribe({
        next: (res) => {
          this.events = res ?? [];
          this.cdr.detectChanges();
        },
        error: (err) => {
          console.error(err);
        }
      });
    }

  onSubmit() {
    this.submitted = true;

    if (this.searchAndImportEventsForm.invalid) {
      console.log(this.searchAndImportEventsForm.errors);
      return;
    }

    const city = this.searchAndImportEventsForm.value.city;

    this.searchOrDownloadEventService.searchOrDownloadEventForm(city).subscribe({
      next: (res) => {
        this.events = res ?? [];
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
