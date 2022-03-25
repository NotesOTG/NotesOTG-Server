using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NotesOTG_Server.Models.Http.Requests;
using NotesOTG_Server.Models.Http.Responses;
using NotesOTG_Server.Models.Http.Responses.impl;
using NotesOTG_Server.Services.Data.Impl;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace NotesOTG_Server.Controllers
{
    public class NotesController : BaseController
    {

        private readonly NotesService notesService;

        public NotesController(NotesService notesService)
        {
            this.notesService = notesService;
        }
/*
        [Authorize]
        [HttpGet("")]
        public async Task<List<NoteResponse>> Index()
        {
            return await notesService.GetAllNotes();
        }*/

        [Authorize]
        [HttpPost("addNote")]
        public async Task<NoteResponse> AddNote(NotesRequest request)
        {
            var addedNote = await notesService.AddNote(request);
            return addedNote;
        }

        [Authorize]
        [HttpDelete("deleteNote")]
        public async Task<BasicResponse> DeleteNote(string publicNoteId)
        {
            var deletedNote = await notesService.DeleteNote(publicNoteId);
            return deletedNote;
        }

        [Authorize]
        [HttpPut("updateNote")]
        public async Task<NoteResponse> UpdateNote(NotesRequest request)
        {
            var updatedNote = await notesService.UpdateNote(request);
            return updatedNote;
        }

    }
}
