import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { getEventDto } from '../../Dto/getEventDto';
import { postCitySearchDto } from '../../Dto/postCitySearchDto';
import { DownloadImportEventService } from '../../Services/DownloadImportEventService';
import { EventService } from '../../Services/EventService';

@Component({
  selector: 'app-search-and-import-events',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
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
    private router: Router,
    private cdr: ChangeDetectorRef,
    private dIEventService: DownloadImportEventService,
    private eventService: EventService,
  ) {
    this.searchAndImportEventsForm = this.fb.group({
      city: ['', [Validators.required]],
    });
  }

  onSubmit() {
    this.submitted = true;

    if (this.searchAndImportEventsForm.invalid) {
      console.log(this.searchAndImportEventsForm.errors);
      return;
    }

    const city = this.searchAndImportEventsForm.value.city;

    this.dIEventService.searchEvent(city).subscribe({
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

  ngOnInit(): void {
    
  }


}
